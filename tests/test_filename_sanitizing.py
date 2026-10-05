"""tests/test_filename_sanitizing.py — security audit findings #1, #2 and #10.

A file name that comes from a peer is attacker-controlled. The audit showed
three ways it could do harm: a traversal path stored as a vault entry's
`original_filename` and later joined onto a temp or export directory (#1, #2),
and names that are invalid or dangerous on Windows -- device names such as
CON/NUL, NTFS alternate data streams (`file.txt:hidden`), trailing dots and
over-long names -- that the receiving path accepted (#10).
"""

import json
import os

import pytest

from core.security.filenames import MAX_FILENAME_BYTES, UnsafeFilenameError, sanitize_filename
from core.transfer.receiver import TransferSecurityError, resolve_safe_dest_path

# --------------------------------------------------------------------------- unit

@pytest.mark.parametrize("name, expected", [
    ("report.pdf", "report.pdf"),
    ("a b (1).txt", "a b (1).txt"),
    ("\u00e9t\u00e9.txt", "\u00e9t\u00e9.txt"),
    ("..\\..\\..\\Startup\\evil_pwn.exe", "evil_pwn.exe"),
    ("../../etc/passwd", "passwd"),
    ("C:\\Windows\\System32\\x.dll", "x.dll"),
    ("/abs/path/file.txt", "file.txt"),
    ("dir/sub\\file.txt", "file.txt"),
    ("  padded.txt  ", "padded.txt"),
    ("tab\there.txt", "tabhere.txt"),
    ("nul\x00byte.txt", "nulbyte.txt"),
    ("...hidden", "...hidden"),
])
@pytest.mark.parametrize("windows", [False, True])
def test_directory_parts_and_control_characters_are_removed(name, expected, windows):
    assert sanitize_filename(name, windows=windows) == expected


@pytest.mark.parametrize("name", ["", ".", "..", "   ", "a/", "a\\", "/", "\\", "../", "..\\", "\x00", None, 5, b"x"])
@pytest.mark.parametrize("windows", [False, True])
def test_names_with_nothing_usable_are_refused(name, windows):
    with pytest.raises(UnsafeFilenameError):
        sanitize_filename(name, windows=windows)
    assert sanitize_filename(name, windows=windows, fallback="file") == "file"


@pytest.mark.parametrize("name, expected", [
    ("report.pdf:hidden", "report.pdf_hidden"),               # NTFS alternate data stream
    ("file.txt::$DATA", "file.txt__$DATA"),
    ('a<b>c|d"e?f*g.txt', "a_b_c_d_e_f_g.txt"),
    ("trailing.dot.", "trailing.dot"),
    ("trailing space. . ", "trailing space"),
    ("CON", "_CON"), ("con.txt", "_con.txt"), ("NUL", "_NUL"), ("Aux.tar.gz", "_Aux.tar.gz"),
    ("COM1", "_COM1"), ("lpt9.log", "_lpt9.log"),
    ("CONSOLE.txt", "CONSOLE.txt"), ("COM10.txt", "COM10.txt"), ("NULL.txt", "NULL.txt"),   # not reserved
    ("...", None),
])
def test_windows_rules_remove_streams_devices_and_trailing_dots(name, expected):
    if expected is None:
        with pytest.raises(UnsafeFilenameError):
            sanitize_filename(name, windows=True)
    else:
        assert sanitize_filename(name, windows=True) == expected


def test_windows_only_rules_do_not_change_names_that_are_fine_elsewhere():
    assert sanitize_filename("report.pdf:hidden", windows=False) == "report.pdf:hidden"
    assert sanitize_filename("CON", windows=False) == "CON"
    assert sanitize_filename("trailing.dot.", windows=False) == "trailing.dot."


@pytest.mark.parametrize("windows", [False, True])
def test_over_long_names_are_shortened_without_breaking_characters_or_the_extension(windows):
    name = ("\u00e9" * 400) + ".tar.gz"
    out = sanitize_filename(name, windows=windows)
    assert len(out.encode("utf-8")) <= MAX_FILENAME_BYTES
    assert out.endswith(".gz") and out.encode("utf-8").decode("utf-8") == out
    assert len(sanitize_filename("n" * 300 + ".txt", windows=windows, max_bytes=100).encode()) <= 100
    assert sanitize_filename("x" * 300 + "." + "e" * 40, windows=windows).startswith("x")


# ---------------------------------------------------------------- receiving path (#10)

@pytest.mark.parametrize("offered, expected", [
    ("..\\..\\Startup\\evil.exe", "evil.exe"),
    ("report.pdf:hidden", "report.pdf_hidden"),
    ("CON.txt", "_CON.txt"),
    ("NUL", "_NUL"),
    ("name. ", "name"),
])
def test_the_receiving_path_applies_the_windows_rules_on_windows(tmp_path, monkeypatch, offered, expected):
    monkeypatch.setattr("core.security.filenames.os.name", "nt")
    out = resolve_safe_dest_path(offered, str(tmp_path))
    assert os.path.basename(out) == expected
    assert os.path.dirname(out) == str(tmp_path)


def test_the_receiving_path_still_rejects_nothing_usable_and_still_dedups(tmp_path):
    for bad in ("", ".", "..", "dir/"):
        with pytest.raises(TransferSecurityError):
            resolve_safe_dest_path(bad, str(tmp_path))
    (tmp_path / "a.txt").write_text("x")
    assert os.path.basename(resolve_safe_dest_path("a.txt", str(tmp_path))) == "a (1).txt"


def test_a_very_long_offered_name_still_leaves_room_for_the_part_suffix(tmp_path):
    out = resolve_safe_dest_path("n" * 400 + ".bin", str(tmp_path))
    assert len((os.path.basename(out) + ".part").encode()) <= MAX_FILENAME_BYTES


# ------------------------------------------------------------------- vault (#1, #2)

def _vault(tmp_path):
    from core.vault.crypto import new_dek
    store = tmp_path / "secure"
    store.mkdir()
    return str(store), new_dek()


def test_a_traversal_name_is_stored_as_a_plain_name(tmp_path):
    from core.vault.secure_file import encrypt_file, load_metadata
    store, dek = _vault(tmp_path)
    src = tmp_path / "payload.bin"
    src.write_bytes(b"data")
    meta = encrypt_file(str(src), store, dek, original_filename="..\\..\\..\\Startup\\evil_pwn.exe")
    assert meta.original_filename == "evil_pwn.exe"
    assert load_metadata(store, meta.secure_id).original_filename == "evil_pwn.exe"


@pytest.mark.parametrize("tampered", ["../../escaped.txt", "..\\..\\escaped.txt", "/abs/dir/../../escaped.txt"])
def test_open_never_writes_outside_its_temp_dir_even_if_the_stored_name_was_tampered(tmp_path, tampered):
    """The metadata sits on disk; whatever put a traversal name there, Open must not follow it.
    (A forward-slash name really escapes on POSIX; the backslash form is the Windows exploit.)"""
    from core.vault.file_actions import open_secure_file
    from core.vault.secure_file import METADATA_EXTENSION, encrypt_file
    store, dek = _vault(tmp_path)
    src = tmp_path / "doc.txt"
    src.write_bytes(b"hello")
    meta = encrypt_file(str(src), store, dek, original_filename="doc.txt")

    meta_file = next(p for p in (tmp_path / "secure").iterdir() if p.name.endswith(METADATA_EXTENSION))
    record = json.loads(meta_file.read_text())
    record["original_filename"] = tampered
    meta_file.write_text(json.dumps(record))

    class Session:
        is_unlocked = True

        def requires_reauth(self, action):
            return False

        def verify_passphrase(self, *a, **k):
            return True

        def dek_bytes(self):
            return dek

    temp_dir = tmp_path / "work" / "tmp_open"
    temp_path, _ = open_secure_file(meta.secure_id, store, Session(), temp_dir=str(temp_dir))

    assert os.path.dirname(temp_path) == str(temp_dir)
    assert os.path.basename(temp_path) == "escaped.txt"
    stray = [p for p in tmp_path.rglob("*escaped.txt") if p.parent != temp_dir]
    assert stray == [], f"written outside the temp dir: {stray}"
