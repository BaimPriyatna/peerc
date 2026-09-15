"""core/vault/secure_file.py — Phase 39.5: per-file encryption/decryption.

See docs/SECURE_STORAGE_DESIGN.md §5, §6, §16. Each secure file gets its
own encryption key derived from the DEK via HKDF with a per-file random
salt, stored alongside the ciphertext as metadata. AES-256-GCM with fresh
random nonces (§16) — same pattern as the vault keyfile and database
encryption, just applied per-file instead of to one monolithic blob.

File naming: opaque secure_id (random hex), not the original filename.
The real filename is metadata, encrypted alongside the content (§6).
"""

import json
import os
import secrets
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SECURE_FILE_EXTENSION = ".peercfile"
METADATA_EXTENSION = ".meta"

FILE_KEY_LEN = 32  # AES-256
NONCE_LEN = 12     # GCM standard 96-bit
SALT_LEN = 16      # per-file salt for HKDF


class SecureFileError(Exception):
    """Base class for secure file encryption/decryption errors."""


class SecureFileCorruptError(SecureFileError):
    """Raised when a secure file can't be decrypted — either wrong DEK,
    corrupted ciphertext, or tampered metadata."""


@dataclass
class SecureFileMetadata:
    """Metadata stored alongside each encrypted file (not secret by itself,
    but encrypted anyway since it contains the original filename)."""
    
    secure_id: str          # opaque identifier (hex)
    original_filename: str  # real filename, kept here not in directory listing
    size: int               # original plaintext size in bytes
    salt: bytes             # per-file HKDF salt (hex-encoded in JSON)
    nonce: bytes            # GCM nonce (hex-encoded in JSON)
    encrypted_at: float     # timestamp
    checksum: Optional[str] = None  # SHA-256 of plaintext (optional, for verification)


def generate_secure_id() -> str:
    """Generate an opaque secure file identifier (32 random bytes = 64 hex chars).
    This becomes the filename in secure storage, replacing the real name."""
    return secrets.token_hex(32)


def _derive_file_key(dek: bytes, salt: bytes) -> bytes:
    """HKDF(DEK, salt, info=domain-separation) -> per-file encryption key.
    Each file gets its own key, distinct from the database key and vault
    keyfile keys. The random salt makes every file's key unique even from
    the same DEK."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=FILE_KEY_LEN,
        salt=salt,
        info=b"peerc-secure-file-v1",
    ).derive(dek)


def encrypt_file(
    plaintext_path: str,
    secure_storage_dir: str,
    dek: bytes,
    original_filename: Optional[str] = None,
    checksum: Optional[str] = None,
) -> SecureFileMetadata:
    """Encrypt a plaintext file into secure storage.
    
    Args:
        plaintext_path: Path to the plaintext file to encrypt
        secure_storage_dir: Directory where secure files are stored
        dek: Data Encryption Key (from unlocked vault)
        original_filename: Real filename (if different from path basename)
        checksum: Optional SHA-256 checksum of plaintext for verification
    
    Returns:
        SecureFileMetadata with secure_id, salt, nonce, etc.
    
    Raises:
        SecureFileError: If encryption fails
        FileNotFoundError: If plaintext_path doesn't exist
    """
    if not os.path.exists(plaintext_path):
        raise FileNotFoundError(f"plaintext file not found: {plaintext_path}")
    
    if not os.path.isdir(secure_storage_dir):
        os.makedirs(secure_storage_dir, mode=0o700, exist_ok=True)
    
    # Read plaintext
    with open(plaintext_path, "rb") as f:
        plaintext = f.read()
    
    # Generate per-file cryptographic material
    secure_id = generate_secure_id()
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    file_key = _derive_file_key(dek, salt)
    
    # Encrypt with AES-256-GCM
    try:
        ciphertext = AESGCM(file_key).encrypt(nonce, plaintext, None)
    except Exception as e:
        raise SecureFileError(f"encryption failed: {e}") from e
    
    # Write encrypted file
    secure_path = os.path.join(
        secure_storage_dir, f"{secure_id}{SECURE_FILE_EXTENSION}"
    )
    with open(secure_path, "wb") as f:
        f.write(ciphertext)
    
    # Create and save metadata
    metadata = SecureFileMetadata(
        secure_id=secure_id,
        original_filename=original_filename or os.path.basename(plaintext_path),
        size=len(plaintext),
        salt=salt,
        nonce=nonce,
        encrypted_at=os.path.getmtime(plaintext_path),
        checksum=checksum,
    )
    _save_metadata(secure_storage_dir, metadata)
    
    return metadata


def decrypt_file(
    secure_id: str,
    secure_storage_dir: str,
    dek: bytes,
    output_path: str,
) -> SecureFileMetadata:
    """Decrypt a secure file to a plaintext output location.
    
    Args:
        secure_id: Opaque identifier of the secure file
        secure_storage_dir: Directory where secure files are stored
        dek: Data Encryption Key (from unlocked vault)
        output_path: Where to write the decrypted plaintext
    
    Returns:
        SecureFileMetadata of the decrypted file
    
    Raises:
        SecureFileCorruptError: If decryption fails (wrong DEK or corrupted)
        FileNotFoundError: If secure file doesn't exist
    """
    # Load metadata
    metadata = load_metadata(secure_storage_dir, secure_id)
    
    # Read ciphertext
    secure_path = os.path.join(
        secure_storage_dir, f"{secure_id}{SECURE_FILE_EXTENSION}"
    )
    if not os.path.exists(secure_path):
        raise FileNotFoundError(f"secure file not found: {secure_path}")
    
    with open(secure_path, "rb") as f:
        ciphertext = f.read()
    
    # Derive the same per-file key
    file_key = _derive_file_key(dek, metadata.salt)
    
    # Decrypt with AES-256-GCM
    try:
        plaintext = AESGCM(file_key).decrypt(metadata.nonce, ciphertext, None)
    except Exception as e:
        raise SecureFileCorruptError(
            f"decryption failed (wrong DEK or corrupted file): {e}"
        ) from e
    
    # Verify size matches metadata
    if len(plaintext) != metadata.size:
        raise SecureFileCorruptError(
            f"size mismatch: expected {metadata.size}, got {len(plaintext)}"
        )
    
    # Write plaintext
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(plaintext)
    
    return metadata


def delete_secure_file(secure_id: str, secure_storage_dir: str) -> None:
    """Delete a secure file and its metadata.
    
    Args:
        secure_id: Opaque identifier of the secure file
        secure_storage_dir: Directory where secure files are stored
    
    Raises:
        FileNotFoundError: If secure file doesn't exist
    """
    secure_path = os.path.join(
        secure_storage_dir, f"{secure_id}{SECURE_FILE_EXTENSION}"
    )
    meta_path = os.path.join(
        secure_storage_dir, f"{secure_id}{METADATA_EXTENSION}"
    )
    
    if not os.path.exists(secure_path):
        raise FileNotFoundError(f"secure file not found: {secure_path}")
    
    # Delete both files
    os.remove(secure_path)
    if os.path.exists(meta_path):
        os.remove(meta_path)


def load_metadata(secure_storage_dir: str, secure_id: str) -> SecureFileMetadata:
    """Load metadata for a secure file.
    
    Args:
        secure_storage_dir: Directory where secure files are stored
        secure_id: Opaque identifier of the secure file
    
    Returns:
        SecureFileMetadata
    
    Raises:
        FileNotFoundError: If metadata file doesn't exist
        SecureFileError: If metadata is corrupted/invalid
    """
    meta_path = os.path.join(
        secure_storage_dir, f"{secure_id}{METADATA_EXTENSION}"
    )
    
    if not os.path.exists(meta_path):
        raise FileNotFoundError(f"metadata not found: {meta_path}")
    
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        return SecureFileMetadata(
            secure_id=data["secure_id"],
            original_filename=data["original_filename"],
            size=data["size"],
            salt=bytes.fromhex(data["salt"]),
            nonce=bytes.fromhex(data["nonce"]),
            encrypted_at=data["encrypted_at"],
            checksum=data.get("checksum"),
        )
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        raise SecureFileError(f"corrupted metadata: {e}") from e


def _save_metadata(secure_storage_dir: str, metadata: SecureFileMetadata) -> None:
    """Save metadata for a secure file (internal helper)."""
    meta_path = os.path.join(
        secure_storage_dir, f"{metadata.secure_id}{METADATA_EXTENSION}"
    )
    
    data = {
        "secure_id": metadata.secure_id,
        "original_filename": metadata.original_filename,
        "size": metadata.size,
        "salt": metadata.salt.hex(),
        "nonce": metadata.nonce.hex(),
        "encrypted_at": metadata.encrypted_at,
        "checksum": metadata.checksum,
    }
    
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def list_secure_files(secure_storage_dir: str) -> list[SecureFileMetadata]:
    """List all secure files in a directory by reading their metadata.
    
    Args:
        secure_storage_dir: Directory where secure files are stored
    
    Returns:
        List of SecureFileMetadata for all files found
    """
    if not os.path.isdir(secure_storage_dir):
        return []
    
    files = []
    for filename in os.listdir(secure_storage_dir):
        if filename.endswith(METADATA_EXTENSION):
            secure_id = filename[: -len(METADATA_EXTENSION)]
            try:
                metadata = load_metadata(secure_storage_dir, secure_id)
                files.append(metadata)
            except (FileNotFoundError, SecureFileError):
                # Skip corrupted/orphaned metadata
                continue
    
    return sorted(files, key=lambda m: m.encrypted_at, reverse=True)
