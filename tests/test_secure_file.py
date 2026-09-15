"""tests/test_secure_file.py — Phase 39.5: per-file encryption tests.

Covers:
  1. encrypt_file + decrypt_file roundtrip (plaintext → encrypted → plaintext).
  2. Metadata preservation (original filename, size, checksum, timestamps).
  3. Each file gets unique salt + nonce (never reused).
  4. decrypt_file with wrong DEK raises SecureFileCorruptError.
  5. Corrupted ciphertext raises SecureFileCorruptError.
  6. Size mismatch (metadata vs. actual plaintext) raises SecureFileCorruptError.
  7. delete_secure_file removes both ciphertext and metadata.
  8. list_secure_files returns all encrypted files sorted by timestamp.
  9. Opaque secure_id naming (not the original filename).
 10. load_metadata succeeds for valid metadata, fails for missing/corrupted.
"""

import os
import secrets

import pytest

from core.vault.crypto import new_dek
from core.vault.secure_file import (
    SecureFileCorruptError,
    SecureFileError,
    SecureFileMetadata,
    decrypt_file,
    delete_secure_file,
    encrypt_file,
    generate_secure_id,
    list_secure_files,
    load_metadata,
)


def test_encrypt_decrypt_roundtrip(tmp_path):
    """Encrypt a file, decrypt it back, verify plaintext matches."""
    plaintext_path = tmp_path / "original.txt"
    plaintext_path.write_text("Hello, secure world!")
    
    secure_dir = tmp_path / "secure"
    dek = new_dek()
    
    # Encrypt
    metadata = encrypt_file(
        str(plaintext_path),
        str(secure_dir),
        dek,
        checksum="dummy_checksum",
    )
    
    assert metadata.original_filename == "original.txt"
    assert metadata.size == len("Hello, secure world!")
    assert metadata.checksum == "dummy_checksum"
    assert len(metadata.secure_id) == 64  # 32 bytes = 64 hex chars
    assert len(metadata.salt) == 16
    assert len(metadata.nonce) == 12
    
    # Verify ciphertext exists and is opaque
    ciphertext_path = secure_dir / f"{metadata.secure_id}.peercfile"
    assert ciphertext_path.exists()
    assert ciphertext_path.read_bytes() != b"Hello, secure world!"
    
    # Decrypt
    output_path = tmp_path / "decrypted.txt"
    meta_restored = decrypt_file(
        metadata.secure_id,
        str(secure_dir),
        dek,
        str(output_path),
    )
    
    assert meta_restored.original_filename == "original.txt"
    assert meta_restored.size == metadata.size
    assert output_path.read_text() == "Hello, secure world!"


def test_metadata_preservation(tmp_path):
    """Verify all metadata fields are preserved across encrypt/decrypt."""
    plaintext_path = tmp_path / "test_file.dat"
    content = b"Binary content \x00\xff" * 100
    plaintext_path.write_bytes(content)
    
    secure_dir = tmp_path / "secure"
    dek = new_dek()
    
    metadata = encrypt_file(
        str(plaintext_path),
        str(secure_dir),
        dek,
        original_filename="custom_name.dat",
        checksum="abc123",
    )
    
    # Reload metadata from disk
    loaded = load_metadata(str(secure_dir), metadata.secure_id)
    
    assert loaded.secure_id == metadata.secure_id
    assert loaded.original_filename == "custom_name.dat"
    assert loaded.size == len(content)
    assert loaded.checksum == "abc123"
    assert loaded.salt == metadata.salt
    assert loaded.nonce == metadata.nonce
    assert loaded.encrypted_at == metadata.encrypted_at


def test_unique_salt_and_nonce_per_file(tmp_path):
    """Each encrypted file must have unique salt and nonce."""
    plaintext = tmp_path / "file.txt"
    plaintext.write_text("Same content")
    
    secure_dir = tmp_path / "secure"
    dek = new_dek()
    
    # Encrypt same file twice
    meta1 = encrypt_file(str(plaintext), str(secure_dir), dek)
    meta2 = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    # Must have different secure_id, salt, nonce
    assert meta1.secure_id != meta2.secure_id
    assert meta1.salt != meta2.salt
    assert meta1.nonce != meta2.nonce
    
    # Both ciphertexts must exist and be different
    cipher1 = (secure_dir / f"{meta1.secure_id}.peercfile").read_bytes()
    cipher2 = (secure_dir / f"{meta2.secure_id}.peercfile").read_bytes()
    assert cipher1 != cipher2


def test_wrong_dek_raises_corrupt_error(tmp_path):
    """Decryption with wrong DEK must fail with SecureFileCorruptError."""
    plaintext = tmp_path / "secret.txt"
    plaintext.write_text("Sensitive data")
    
    secure_dir = tmp_path / "secure"
    correct_dek = new_dek()
    wrong_dek = new_dek()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), correct_dek)
    
    output = tmp_path / "out.txt"
    with pytest.raises(SecureFileCorruptError):
        decrypt_file(metadata.secure_id, str(secure_dir), wrong_dek, str(output))


def test_corrupted_ciphertext_raises_corrupt_error(tmp_path):
    """Tampering with ciphertext must be detected and rejected."""
    plaintext = tmp_path / "data.txt"
    plaintext.write_text("Important data")
    
    secure_dir = tmp_path / "secure"
    dek = new_dek()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    # Corrupt the ciphertext
    ciphertext_path = secure_dir / f"{metadata.secure_id}.peercfile"
    corrupted = bytearray(ciphertext_path.read_bytes())
    corrupted[10] ^= 0xFF  # flip some bits
    ciphertext_path.write_bytes(bytes(corrupted))
    
    output = tmp_path / "out.txt"
    with pytest.raises(SecureFileCorruptError):
        decrypt_file(metadata.secure_id, str(secure_dir), dek, str(output))


def test_size_mismatch_raises_corrupt_error(tmp_path):
    """Plaintext size mismatch vs. metadata must be detected."""
    plaintext = tmp_path / "file.txt"
    plaintext.write_text("Original content")
    
    secure_dir = tmp_path / "secure"
    dek = new_dek()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    # Manually tamper with metadata size
    import json
    meta_path = secure_dir / f"{metadata.secure_id}.meta"
    meta_data = json.loads(meta_path.read_text())
    meta_data["size"] = 9999  # wrong size
    meta_path.write_text(json.dumps(meta_data))
    
    output = tmp_path / "out.txt"
    with pytest.raises(SecureFileCorruptError, match="size mismatch"):
        decrypt_file(metadata.secure_id, str(secure_dir), dek, str(output))


def test_delete_secure_file_removes_both_files(tmp_path):
    """delete_secure_file must remove both .peercfile and .meta."""
    plaintext = tmp_path / "temp.txt"
    plaintext.write_text("Temporary file")
    
    secure_dir = tmp_path / "secure"
    dek = new_dek()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    cipher_path = secure_dir / f"{metadata.secure_id}.peercfile"
    meta_path = secure_dir / f"{metadata.secure_id}.meta"
    
    assert cipher_path.exists()
    assert meta_path.exists()
    
    delete_secure_file(metadata.secure_id, str(secure_dir))
    
    assert not cipher_path.exists()
    assert not meta_path.exists()


def test_delete_nonexistent_file_raises_error(tmp_path):
    """Attempting to delete a non-existent secure file must raise FileNotFoundError."""
    secure_dir = tmp_path / "secure"
    secure_dir.mkdir()
    
    fake_id = "0" * 64
    with pytest.raises(FileNotFoundError):
        delete_secure_file(fake_id, str(secure_dir))


def test_list_secure_files_sorted_by_timestamp(tmp_path):
    """list_secure_files must return files sorted by encrypted_at descending."""
    plaintext1 = tmp_path / "file1.txt"
    plaintext1.write_text("First")
    plaintext2 = tmp_path / "file2.txt"
    plaintext2.write_text("Second")
    plaintext3 = tmp_path / "file3.txt"
    plaintext3.write_text("Third")
    
    secure_dir = tmp_path / "secure"
    dek = new_dek()
    
    import time
    
    meta1 = encrypt_file(str(plaintext1), str(secure_dir), dek)
    time.sleep(0.01)
    meta2 = encrypt_file(str(plaintext2), str(secure_dir), dek)
    time.sleep(0.01)
    meta3 = encrypt_file(str(plaintext3), str(secure_dir), dek)
    
    files = list_secure_files(str(secure_dir))
    
    assert len(files) == 3
    # Most recent first
    assert files[0].secure_id == meta3.secure_id
    assert files[1].secure_id == meta2.secure_id
    assert files[2].secure_id == meta1.secure_id


def test_list_secure_files_empty_directory(tmp_path):
    """list_secure_files on empty directory returns empty list."""
    secure_dir = tmp_path / "secure"
    secure_dir.mkdir()
    
    files = list_secure_files(str(secure_dir))
    assert files == []


def test_list_secure_files_nonexistent_directory(tmp_path):
    """list_secure_files on non-existent directory returns empty list."""
    secure_dir = tmp_path / "nonexistent"
    
    files = list_secure_files(str(secure_dir))
    assert files == []


def test_opaque_secure_id_naming(tmp_path):
    """Encrypted files must use opaque secure_id, not original filename."""
    plaintext = tmp_path / "sensitive_document.pdf"
    plaintext.write_text("Confidential")
    
    secure_dir = tmp_path / "secure"
    dek = new_dek()
    
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    # Verify secure_id is random hex, not related to filename
    assert metadata.secure_id != "sensitive_document"
    assert len(metadata.secure_id) == 64
    assert all(c in "0123456789abcdef" for c in metadata.secure_id)
    
    # Verify ciphertext filename doesn't reveal original name
    ciphertext_path = secure_dir / f"{metadata.secure_id}.peercfile"
    assert ciphertext_path.exists()
    assert "sensitive_document" not in str(ciphertext_path)


def test_generate_secure_id_uniqueness():
    """generate_secure_id must produce unique IDs."""
    ids = [generate_secure_id() for _ in range(100)]
    assert len(set(ids)) == 100  # all unique


def test_load_metadata_missing_file(tmp_path):
    """load_metadata for missing file must raise FileNotFoundError."""
    secure_dir = tmp_path / "secure"
    secure_dir.mkdir()
    
    with pytest.raises(FileNotFoundError):
        load_metadata(str(secure_dir), "nonexistent_id")


def test_load_metadata_corrupted_json(tmp_path):
    """load_metadata with corrupted JSON must raise SecureFileError."""
    secure_dir = tmp_path / "secure"
    secure_dir.mkdir()
    
    # Create a corrupted .meta file
    meta_path = secure_dir / "test_id.meta"
    meta_path.write_text("not valid json {{{")
    
    with pytest.raises(SecureFileError, match="corrupted metadata"):
        load_metadata(str(secure_dir), "test_id")


def test_encrypt_file_creates_secure_dir_if_missing(tmp_path):
    """encrypt_file must auto-create secure_storage_dir if it doesn't exist."""
    plaintext = tmp_path / "file.txt"
    plaintext.write_text("Content")
    
    secure_dir = tmp_path / "new_secure_dir"
    assert not secure_dir.exists()
    
    dek = new_dek()
    metadata = encrypt_file(str(plaintext), str(secure_dir), dek)
    
    assert secure_dir.exists()
    assert secure_dir.is_dir()
    assert (secure_dir / f"{metadata.secure_id}.peercfile").exists()
