"""
CredX Vault - Encryption Utilities (v3.0 Zero-Knowledge)
Implements industry-standard key derivation (Argon2id/PBKDF2) and AES-256-GCM encryption.
"""

import base64
import ctypes
import os
import secrets
from typing import Literal

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Try to import argon2, fallback to PBKDF2 if not available
try:
    from argon2.low_level import Type, hash_secret_raw
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

# Import KDF parameters from config (single source of truth)
from .config import (
    DEFAULT_ARGON2_MEMORY_COST,
    DEFAULT_ARGON2_PARALLELISM,
    DEFAULT_ARGON2_TIME_COST,
    DEFAULT_KDF_ALGORITHM,
    DEFAULT_PBKDF2_ITERATIONS,
)

# CONSTANTS
MASTER_KEY_SIZE = 32
SYMMETRIC_KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 12

def secure_wipe(buffer: bytearray | memoryview | bytes):
    """
    Surgically overwrite memory at the buffer level.
    """
    if not buffer or isinstance(buffer, bytes):
        return
        
    try:
        if isinstance(buffer, bytearray):
            size = len(buffer)
            address = (ctypes.c_char * size).from_buffer(buffer)
            ctypes.memset(address, 0, size)
        elif isinstance(buffer, memoryview):
            if not buffer.readonly:
                size = buffer.nbytes
                address = (ctypes.c_char * size).from_buffer(buffer)
                ctypes.memset(address, 0, size)
            buffer.release()
    except Exception:
        try:
            for i in range(len(buffer)):
                buffer[i] = 0
        except Exception:
            pass

def derive_blind_index(data: str, key: bytearray | bytes) -> str:
    """
    Derive a deterministic blind index for a string.
    """
    if not data:
        return ""
    
    h = hmac.HMAC(bytes(key), hashes.SHA256())
    h.update(data.lower().strip().encode("utf-8"))
    return h.finalize()[:16].hex()

def derive_blind_index_key(master_key: bytearray | bytes) -> bytearray:
    """
    Derive a specific key for blind indexing using HKDF.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=MASTER_KEY_SIZE,
        salt=None,
        info=b"credx_blind_index_key_v3",
    )
    return bytearray(hkdf.derive(bytes(master_key)))

def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_SIZE)

def generate_symmetric_key() -> bytes:
    return secrets.token_bytes(SYMMETRIC_KEY_SIZE)

def derive_master_key(
    password: bytearray | bytes | str,
    salt: bytes,
    kdf_algorithm: Literal["argon2id", "pbkdf2"] = DEFAULT_KDF_ALGORITHM,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    memory_cost: int = DEFAULT_ARGON2_MEMORY_COST,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
    pbkdf2_iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> bytearray:
    """
    Derive a 32-byte master key from password and salt.
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
        
    if kdf_algorithm == "argon2id":
        if not ARGON2_AVAILABLE:
            raise ValueError("Argon2 not available.")
        
        raw_hash = hash_secret_raw(
            secret=bytes(password),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=MASTER_KEY_SIZE,
            type=Type.ID,
        )
        return bytearray(raw_hash)
    
    elif kdf_algorithm == "pbkdf2":
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=MASTER_KEY_SIZE,
            salt=salt,
            iterations=pbkdf2_iterations,
        )
        return bytearray(kdf.derive(bytes(password)))
    
    else:
        raise ValueError(f"Unknown KDF algorithm: {kdf_algorithm}")

def derive_auth_key(master_key: bytearray | bytes) -> bytearray:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=MASTER_KEY_SIZE,
        salt=None,
        info=b"credx_auth_key_v3",
    )
    return bytearray(hkdf.derive(bytes(master_key)))

def derive_encryption_key(master_key: bytearray | bytes) -> bytearray:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=MASTER_KEY_SIZE,
        salt=None,
        info=b"credx_encryption_key_v3",
    )
    return bytearray(hkdf.derive(bytes(master_key)))

def encrypt_aead(plaintext: str | bytes | bytearray, key: bytearray | bytes) -> str:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(bytes(key))
    ciphertext = aesgcm.encrypt(nonce, bytes(plaintext) if isinstance(plaintext, bytearray) else plaintext, None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

def decrypt_aead(ciphertext: str, key: bytearray | bytes) -> str:
    data = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
    nonce = data[:NONCE_SIZE]
    ciphertext_with_tag = data[NONCE_SIZE:]
    
    aesgcm = AESGCM(bytes(key))
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext.decode("utf-8")

def bytes_to_base64(data: bytes | bytearray) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")

def base64_to_bytes(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))

def key_to_hex(key: bytes | bytearray) -> str:
    return key.hex()
